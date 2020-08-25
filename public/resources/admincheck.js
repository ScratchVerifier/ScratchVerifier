document.onload = ()=>{
    if (localStorage.getItem("isAdmin") !== "true"){
        location.pathname = "/admin/access_denied.html"
        document.write("Not Authorized")
    }
}