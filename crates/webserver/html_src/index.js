let g_canvas_state = {
  element: null,
  context: null,
  width: 0,
  height: 0,
};
let socket = null;
$(document).ready(main);

function main() {
  $(".login")[0].showModal()
  create_socket();
  resize_canvas();
  $(window).resize(resize_canvas);
  draw();
}

function create_socket() {
  socket = new WebSocket(document.location.href + "ws");
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
  return {salt: saltStr, key: key};
}

function hash_with_salt(password, saltStr) {
  //construct salt from string
  let salt = CryptoJS.enc.Base64.parse(saltStr)
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 1024 / 32, //uber large key size
    iterations: 100000 //good f**king luck cracking these
  }).toString();
}

function handleOpen(event) {}

function handleError(event) {}

function handleClose(event) {

}
