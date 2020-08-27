document.onload = () => {
    if (localStorage.getItem("isAdmin") !== "true") {
        localStorage.setItem("isAdmin", "false")
        location.replace("/site/admin/access_denied.html")
    }
}