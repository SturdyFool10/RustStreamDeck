let g_canvas_state = {
  element: null,
  context: null,
  width: 0,
  height: 0,
};
let socket = null;
let salt_recv_handler = function () {
  console.log("salt_recv_handler");
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
