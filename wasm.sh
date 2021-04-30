cargo build --release --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/PasswordChkr.wasm --out-dir web --web
cat << EOF > web/index.html
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-type" content="text/html; charset=utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Password Checker 2000</title>
  </head>
  <body>
    <script type="module">
      import init from "./PasswordChkr.js";

      init('./PasswordChkr_bg.wasm');
    </script>
  </body>
</html> 
EOF
