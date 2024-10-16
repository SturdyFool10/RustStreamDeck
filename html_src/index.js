$(document).ready(main);

function main() {
  var socket = new WebSocket(document.location.href + "/ws");
  socket.onmessage = handleMessage;
  socket.onopen = handleOpen;
  socket.onerror = handleError;
  socket.onclose = handleClose;
}

function handleMessage(event) {}

function handleOpen(event) {}

function handleError(event) {}

function handleClose(event) {}
