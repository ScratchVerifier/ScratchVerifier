window.globalErrors = []
globalErrors.onerror = (err) => {
  if (document.readyState === "complete"){
    document.write("A error occoured, the error has been reported. Error:<br>" + err + "<br><br>")
  } else {
    addEventListener("load",()=>{
      document.write("A error occoured, the error has been reported. Error:<br>" + err + "<br><br>")
    })
  }
}
window.onerror = function (msg, url, line, col, error) {
    // Note that col & error are new to the HTML 5 spec and may not be
    // supported in every browser.  It worked for me in Chrome.
    var extra = `Message: ${msg}, url: ${url}, line: ${line}, col: ${col}, error: ${error}`
    if (error) {
        extra = error
    }
    globalErrors.push(extra)
    globalErrors.onerror(extra)
    return true;
}
