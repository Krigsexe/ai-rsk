// Safe: regex.exec() is a standard JS method, not code injection
const regex = /pattern/g;
const match = regex.exec(inputString);

// Safe: Array method that sounds like exec
const result = tasks.find(task => task.execute(data));

// Safe: JSON.parse instead of eval
const data = JSON.parse(userInput);

// Safe: setTimeout with function reference (not string)
setTimeout(myFunction, 1000);

// Safe: setInterval with arrow function
setInterval(() => checkStatus(), 5000);

// Safe: comment mentioning eval without calling it
// We used to use eval here but replaced it with JSON.parse

// Safe: variable named evaluate
const evaluate = (expr) => mathjs.evaluate(expr);

// Safe: execSync used in a build script context (test file excluded)
// This file is in safe/ fixtures so it should NOT match
