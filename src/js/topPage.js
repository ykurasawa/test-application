function execute() {
  var elem = document.getElementById("output");
  var now = new Date();
  var hour = now.getHours();
  var min = now.getMinutes();
  elem.innerHTML = "ただいまの時刻は" + hour + ":" + min + "です";
}

