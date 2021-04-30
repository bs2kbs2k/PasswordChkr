use futures::executor::block_on;
use hex::ToHex;
use sha1::{Digest, Sha1};
use std::str::FromStr;

use iced::{
    button, executor, progress_bar, text_input, Application, Clipboard, Column, Command, Element,
    Executor, ProgressBar, Settings, Text,
};
use std::env;
use zxcvbn::{zxcvbn, Entropy, ZxcvbnError};

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
        Element::from(
            Column::new()
                .push(
                    text_input::TextInput::new(
                        &mut self.password_input,
                        "Password",
                        self.password.as_str(),
                        |password| Message::PasswordChanged(password),
                    )
                    .padding(8),
                )
                .push(ProgressBar::new(
                    (0.0..=4.0),
                    *&self
                        .entropy
                        .as_ref()
                        .and_then(|entropy| Ok(f32::from(entropy.score())))
                        .unwrap_or(0.0),
                ))
                .push(Text::new(match &self.entropy {
                    Ok(entropy) => format!(
                        "Score:{}/4\nReason: {}\nSuggestions:\n{}",
                        entropy.score(),
                        entropy
                            .feedback()
                            .as_ref()
                            .and_then(|feedback| Some(
                                feedback
                                    .warning()
                                    .and_then(|warning| Some(warning.to_string()))
                                    .unwrap_or("No reason provided".to_string())
                            ))
                            .unwrap_or("No feedback provided".to_string()),
                        entropy
                            .feedback()
                            .as_ref()
                            .and_then(|feedback| Some(
                                feedback
                                    .suggestions()
                                    .iter()
                                    .map(|suggestion| suggestion.to_string())
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            ))
                            .unwrap_or("No feedback provided".to_string())
                    ),
                    Err(error) => error.to_string(),
                }))
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
                })),
        )
    }
}

fn main() -> Result<(), iced::Error> {
    State::run(Settings::default())
}

async fn check_pwned_passwords(password: String) -> Result<usize, String> {
    let digest = Sha1::digest(password.as_bytes()).encode_hex_upper::<String>();
    let (prefix, suffix) = digest.split_at(5);
    surf::get("https://api.pwnedpasswords.com/range/".to_owned() + prefix)
        .await
        .map_err(|error| format!("{}", error))?
        .body_string()
        .await
        .map_err(|error| format!("{}", error))?
        .lines()
        .filter(|a| a.starts_with(suffix))
        .collect::<Vec<_>>()
        .get(0)
        .map_or(Ok(0), |a| {
            Ok(usize::from_str(a.split(":").collect::<Vec<_>>().last().unwrap()).unwrap())
        })
}
