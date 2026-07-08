// Benign JavaScript - should NOT trigger any YARA rules
var x = document.getElementById("main");
x.innerHTML = "Hello World";
console.log("test");
