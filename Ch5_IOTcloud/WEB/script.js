// Import necessary Firebase libraries
import { initializeApp } from 'https://www.gstatic.com/firebasejs/9.6.0/firebase-app.js';
import { getDatabase, ref, onValue } from 'https://www.gstatic.com/firebasejs/9.6.0/firebase-database.js';

// Firebase configuration
  const firebaseConfig = {

    apiKey: "AIzaSyBArRYMXZdKh6h8XRqM3_GU7ZkIwxGgCeM",
    authDomain: "iot-cseh.firebaseapp.com",
    databaseURL: "https://iot-cseh-default-rtdb.asia-southeast1.firebasedatabase.app",
    projectId: "iot-cseh",
    storageBucket: "iot-cseh.firebasestorage.app",
    messagingSenderId: "122411437092",
    appId: "1:122411437092:web:6c4a05110683433e14dcb1"
  };


// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const database = getDatabase(firebaseApp);

function xorDecrypt(encryptedHex, encryptionKey) {
    return encryptedHex.match(/.{2}/g) // Split into pairs
        .map(hex => String.fromCharCode(parseInt(hex, 16))) // Convert hex to text
        .map(char => String.fromCharCode(char.charCodeAt(0) ^ encryptionKey)) // XOR operation
        .join(''); // Join back into a string
}

// Authenticate user
export function authenticate() {
    const usernameInput = document.getElementById('userId');
    const passwordInput = document.getElementById('password');
    const enteredPassword = passwordInput.value;
    const enteredUsername = usernameInput.value.split('@')[0];

    // Fetch the correct password from Firebase
    const passwordRef = ref(database, `/${enteredUsername}/cseh_password`);
    onValue(passwordRef, (snapshot) => {
        const correctPassword = snapshot.val();

        // get data 
        sessionStorage.setItem('username', enteredUsername);
            localStorage.setItem('username', enteredUsername);
            localStorage.setItem('password', enteredPassword);

            document.getElementById('login-container').style.display = 'none';
            document.getElementById('data-container').style.display = 'block';

        if (enteredPassword === correctPassword) {
            // Correct password
            fetchAndDisplayData_decrypted(enteredUsername);
        } 
        else if(correctPassword==null){
            alert("Username Not In Database")
            logout()
            return;
        }
        else {
            fetchAndDisplayData(enteredUsername); 
        }
        
    }, (error) => {
        console.error("Error authenticating user:", error);
        alert("An error occurred while logging in. Please try again.");
    });
}

// Fetch and display data from Firebase
function fetchAndDisplayData(userId) {

    const value_from_db_ref = ref(database, `/${userId}/values1`);
    const value_from_db_ref1 = ref(database, `/${userId}/values2`);
    const value_from_db_ref2 = ref(database, `/${userId}/values3`);
    const value_from_db_ref3 = ref(database, `/${userId}/values4`);

    onValue(value_from_db_ref, (snapshot) => {
        const value_from_db = snapshot.val();
        console.log(value_from_db)
        document.getElementById("value-cseh").innerHTML = value_from_db;
    });
    onValue(value_from_db_ref1, (snapshot) => {
        const value_from_db = snapshot.val();
        console.log(value_from_db)
        document.getElementById("value-cseh1").innerHTML = value_from_db;
    });
    onValue(value_from_db_ref2, (snapshot) => {
        const value_from_db = snapshot.val();
        console.log(value_from_db)
        document.getElementById("value-cseh2").innerHTML = value_from_db;
    });
    onValue(value_from_db_ref3, (snapshot) => {
        const value_from_db = snapshot.val();
        console.log(value_from_db)
        document.getElementById("value-cseh3").innerHTML = value_from_db;
    });
    
}

// Fetch and display data from Firebase
function fetchAndDisplayData_decrypted(userId) {

    const value_from_db_ref = ref(database, `/${userId}/values1`);
    const value_from_db_ref1 = ref(database, `/${userId}/values2`);
    const value_from_db_ref2 = ref(database, `/${userId}/values3`);
    const value_from_db_ref3 = ref(database, `/${userId}/values4`);
    
    onValue(value_from_db_ref, (snapshot) => {
        const encryptedValue = snapshot.val();

        // Decrypt the received value
        const encryptionKey = 42;  // Must be the same key as used for encryption
        const decryptedValue = xorDecrypt(encryptedValue, encryptionKey);

        console.log("Encrypted Value:", encryptedValue);
        console.log("Decrypted Value:", decryptedValue);

        document.getElementById("value-cseh").innerHTML = decryptedValue;
    });
    onValue(value_from_db_ref1, (snapshot) => {
        const encryptedValue = snapshot.val();

        // Decrypt the received value
        const encryptionKey = 42;  // Must be the same key as used for encryption
        const decryptedValue = xorDecrypt(encryptedValue, encryptionKey);

        console.log("Encrypted Value:", encryptedValue);
        console.log("Decrypted Value:", decryptedValue);

        document.getElementById("value-cseh1").innerHTML = decryptedValue;
    });
    onValue(value_from_db_ref2, (snapshot) => {
        const encryptedValue = snapshot.val();

        // Decrypt the received value
        const encryptionKey = 42;  // Must be the same key as used for encryption
        const decryptedValue = xorDecrypt(encryptedValue, encryptionKey);

        console.log("Encrypted Value:", encryptedValue);
        console.log("Decrypted Value:", decryptedValue);

        document.getElementById("value-cseh2").innerHTML = decryptedValue;
    });
    onValue(value_from_db_ref3, (snapshot) => {
        const encryptedValue = snapshot.val();

        // Decrypt the received value
        const encryptionKey = 42;  // Must be the same key as used for encryption
        const decryptedValue = xorDecrypt(encryptedValue, encryptionKey);

        console.log("Encrypted Value:", encryptedValue);
        console.log("Decrypted Value:", decryptedValue);

        document.getElementById("value-cseh3").innerHTML = decryptedValue;
    });
}

// Logout Function
function logout() {
    // Clear stored credentials
    localStorage.removeItem('username');
    localStorage.removeItem('password');
    sessionStorage.removeItem('username');

    // Hide data container and show login form
    document.getElementById('data-container').style.display = 'none';
    document.getElementById('login-container').style.display = 'block';

    alert("Logged out successfully!");
}


// Handle login form submission
document.getElementById('login-form').addEventListener('submit', (e) => {
    e.preventDefault();
    authenticate();
});


// Attach event listener to the logout button
document.getElementById('logout-button').addEventListener('click', logout);
