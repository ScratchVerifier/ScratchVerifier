function showOrHide(elem) {
  elem = elem.nextElementSibling;
  if (elem.style.display == 'none') {
    elem.style.display = null;
  } else {
    elem.style.display = 'none';
  }
}
