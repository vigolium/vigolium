var http = new XMLHttpRequest();
var params = JSON.stringify({ appoverGUID: approverGUID });
http.open("POST", "/api/get", true);

http.setRequestHeader("Content-type", "application/json; charset=utf-8");
http.setRequestHeader("Content-length", params.length);
http.setRequestHeader("Connection", "close");

http.onreadystatechange = function () {
    if (http.readyState == 4 && http.status == 200) {
        alert(http.responseText);
    }
}
http.send(params);
