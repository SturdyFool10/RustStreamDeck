let g_canvas_state = {
  element: null,
  context: null,
  width: 0,
  height: 0,
};
let socket = null;
let salt_recv_handler = function (data) {
  console.log("salt_recv_handler");
  console.log(data);
  //rest of the data is the salt in utf8
  let salt = new TextDecoder().decode(data);
  let passwordField = $(".login-password");
  let usernameField = $(".login-username");
  let password = passwordField.val();
  let username = usernameField.val();
  console.log("" + username + " " + password + " " + salt + "");
  let hashed = hash_with_salt(password, salt);
  let username_len = username.length;
  let password_len = hashed.length;
  let utf8_username = new TextEncoder().encode(username);
  let utf8_password = new TextEncoder().encode(hashed);
  let buffer = new ArrayBuffer(
    20 + utf8_username.length + utf8_password.length,
  );
  let view = new DataView(buffer);
  view.setUint16(0, 0x5f10, false);
  view.setUint16(2, 0x0002, false);
  view.setBigUint64(4, BigInt(username_len), false);
  view.setBigUint64(12, BigInt(password_len), false);
  let CredentialsUnion = new TextEncoder().encode(username + hashed);
  for (let i = 0; i < CredentialsUnion.length; i++) {
    view.setUint8(20 + i, CredentialsUnion[i]);
  }
  console.log("Sending login request");
  console.log(buffer);
  socket.send(buffer);
};
$(document).ready(main);

function main() {
  $(".login")[0].showModal();
  prepare_modal();
  create_socket();
  resize_canvas();
  $(window).resize(resize_canvas);
  draw();
}

function prepare_modal() {
  let modal = $(".login")[0];
  let submitbtn = $(".loginbtn");
  let usernameField = $(".login-username");
  let passwordField = $(".login-password");
  submitbtn.click(handle_login);
}

function handle_login(e) {
  //guard clause returns if not left click
  if (e.button != 0) {
    return;
  }
  let usernameField = $(".login-username");
  let passwordField = $(".login-password");
  let username = usernameField.val();
  if (socket == null) {
    return;
  }
  //we need to request salt for username to start the login process
  //create a buffer of bytes to send to the server, format is 2 byte header, expected to be 0x5f10, a 2 byte opcode in big endian, with the rest being the username encoded in utf8
  //encode the username in utf8
  let utf8 = new TextEncoder().encode(username);
  let buffer = new ArrayBuffer(4 + utf8.length);
  let view = new DataView(buffer);
  view.setUint16(0, 0x5f10, false);
  view.setUint16(2, 0x0001, false);
  for (let i = 0; i < utf8.length; i++) {
    view.setUint8(4 + i, utf8[i]);
  }
  socket.send(buffer);
}

function create_socket() {
  socket = new WebSocket((document.location.href + "ws").replace("#", ""));
  socket.onmessage = handleMessage;
  socket.onopen = handleOpen;
  socket.onerror = handleError;
  socket.onclose = handleClose;
}

function draw() {
  requestAnimationFrame(draw);
}

function resize_canvas() {
  $("canvas").remove();
  let bod = $("body");
  let canvas = $("<canvas>")
    .attr("width", bod.width())
    .attr("height", bod.height())
    .addClass("main-canvas")[0];
  $("#main-content").append(canvas);
  g_canvas_state.element = canvas;
  g_canvas_state.context = canvas.getContext("2d");
  g_canvas_state.width = canvas.width;
  g_canvas_state.height = canvas.height;
}

function handleMessage(event) {
  console.log(event);
  let data = event.data;
  //check if data is a string or blob
  console.log(typeof data);
  if (typeof data === "string") {
  } else if (data instanceof Blob) {
    //blob should have header of 0x5f10, opcode, and then the rest of the data which is varied depending on what the opcode is
    //read the whole packet into a buffer
    let reader = new FileReader();
    reader.onload = function (e) {
      let buffer = e.target.result;
      let view = new DataView(buffer);
      let header = view.getUint16(0, false);
      let opcode = view.getUint16(2, false);
      if (header != 0x5f10) {
        console.log("invalid header");
        return;
      }
      console.log("got a blob");
      let data = new Uint8Array(buffer, 4);
      switch (opcode) {
        case 0x0001:
          salt_recv_handler(data);
          break;
        default:
          console.log("unknown opcode");
          break;
      }
    };
    reader.readAsArrayBuffer(data);
  }
  console.log(data);
}

//returns a hashed password with fresh salt, if you are trying to hash a
// password that already has predefined salt see hash_with_salt
function hash_password(password) {
  let salt = CryptoJS.lib.WordArray.random(256 / 8);
  let saltStr = CryptoJS.enc.Base64.stringify(salt);
  const key = hash_with_salt(password, saltStr).toString();
  return { salt: saltStr, key: key };
}

function hash_with_salt(password, saltStr) {
  //construct salt from string
  let salt = CryptoJS.enc.Base64.parse(saltStr);
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 1024 / 32, //uber large key size
    iterations: 100000, //good f**king luck cracking these
  }).toString();
}

function handleOpen(event) {}

function handleError(event) {}

function handleClose(event) {}
