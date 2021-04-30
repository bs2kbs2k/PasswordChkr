use hex::ToHex;
use sha1::{Digest, Sha1};
use std::str::FromStr;

use iced::{
    button, executor, text_input, Align, Application, Clipboard, Column, Command, Container,
    Element, Length, ProgressBar, Settings, Text,
};
use zxcvbn::{zxcvbn, Entropy};

struct State {
    password: String,
    password_input: text_input::State,
    check_button: button::State,
    entropy: Result<Entropy, String>,
    leak_num: Result<usize, String>,
}

#[derive(Debug, Clone)]
enum Message {
    PasswordChanged(String),
    CheckDatabase,
    ResultFetched(Result<usize, String>),
}

impl Application for State {
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();

    fn new(flags: Self::Flags) -> (Self, Command<Self::Message>) {
        (
            Self {
                password: "".to_string(),
                password_input: Default::default(),
                check_button: Default::default(),
                entropy: Err("No data".to_string()),
                leak_num: Err("Not checked yet".to_string()),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        "Password Checker 2000".to_string()
    }

    fn update(
        &mut self,
        message: Self::Message,
        clipboard: &mut Clipboard,
    ) -> Command<Self::Message> {
        match message {
            Message::CheckDatabase => {
                self.leak_num = Err("Checking Password".to_string());
                Command::perform(check_pwned_passwords(self.password.clone()), |result| {
                    Message::ResultFetched(result)
                })
            }
            Message::PasswordChanged(password) => {
                self.password = password.clone();
                self.leak_num = Err("Not checked yet".to_string());
                self.entropy =
                    zxcvbn(&*password, [].as_ref()).map_err(|error| format!("{}", error));
                Command::none()
            }
            Message::ResultFetched(result) => {
                self.leak_num = result;
                Command::none()
            }
        }
    }

    fn view(&mut self) -> Element<'_, Self::Message> {
        let mut root = Column::new()
            .push(
                text_input::TextInput::new(
                    &mut self.password_input,
                    "Password",
                    self.password.as_str(),
                    Message::PasswordChanged,
                )
                .padding(8),
            )
            .push(ProgressBar::new(
                0.0..=4.0,
                self.entropy
                    .as_ref()
                    .map(|entropy| f32::from(entropy.score()))
                    .unwrap_or(0.0),
            ));
        match &self.entropy {
            Ok(entropy) => {
                root = root.push(Text::new(format!("Score: {}/4", entropy.score())));
                match entropy.feedback() {
                    None => {
                        root = root.push(Text::new("No feedback provided".to_string()));
                    }
                    Some(feedback) => {
                        match feedback.warning() {
                            None => {}
                            Some(reason) => {
                                root =
                                    root.push(Text::new(format!("Reason: {}", reason.to_string())));
                            }
                        };
                        if !feedback.suggestions().is_empty() {
                            root = root.push(Text::new("Suggestions:"));
                            for suggestion in feedback.suggestions() {
                                root = root.push(Text::new(suggestion.to_string()));
                            }
                        }
                    }
                }
            }
            Err(error) => {
                root = root.push(Text::new(error.to_string()));
            }
        }
        root = root
            .push(
                button::Button::new(
                    &mut self.check_button,
                    Text::new("Check on pwned passwords"),
                )
                .on_press(Message::CheckDatabase),
            )
            .push(Text::new(match &self.leak_num {
                Ok(entropy) => format!("Found {} times", entropy),
                Err(error) => error.to_string(),
            }));
        Element::from(
            Container::new(
                Container::new(root)
                    .width(Length::Units(512))
                    .height(Length::Units(512)),
            )
            .center_x()
            .center_y()
            .width(Length::Fill)
            .height(Length::Fill),
        )
    }
}

fn main() -> Result<(), iced::Error> {
    State::run(Settings::default())
}

async fn check_pwned_passwords(password: String) -> Result<usize, String> {
    let digest = Sha1::digest(password.as_bytes()).encode_hex_upper::<String>();
    let (prefix, suffix) = digest.split_at(5);
    reqwest::get("https://api.pwnedpasswords.com/range/".to_owned() + prefix)
        .await
        .map_err(|error| format!("{}", error))?
        .text()
        .await
        .map_err(|error| format!("{}", error))?
        .lines()
        .filter(|a| a.starts_with(suffix))
        .collect::<Vec<_>>()
        .get(0)
        .map_or(Ok(0), |a| {
            Ok(usize::from_str(a.split(':').collect::<Vec<_>>().last().unwrap()).unwrap())
        })
}
