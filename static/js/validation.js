function validateIP() {
    var ipInput = document.getElementById("ip_address");
    var ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

    if (!ipPattern.test(ipInput.value)) {
        alert("Please enter a valid IP address.");
        return false;
    }

    return true;
}
