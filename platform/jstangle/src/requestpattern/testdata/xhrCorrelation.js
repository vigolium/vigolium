function loadItems() {
  var req = new XMLHttpRequest();
  req.open("GET", "/api/xhr/items?page=1");
  req.setRequestHeader("Accept", "application/json");
  req.setRequestHeader("Cookie", "session=xyz; theme=dark");
  req.send();
}
