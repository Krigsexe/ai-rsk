// Vulnerable: eval with dynamic input
const userInput = req.body.expression;
eval(userInput);

// Vulnerable: eval with template literal
eval(`return ${userExpression}`);

// Vulnerable: new Function with variable
const fn = new Function('x', userCode);

// Vulnerable: setTimeout with string (acts as eval)
setTimeout("alert(document.cookie)", 1000);

// Vulnerable: setInterval with string
setInterval("sendData(secret)", 5000);

// Vulnerable: Python-style exec
exec(user_command)
