// VULNERABLE: PII stored directly in browser storage
// Violates RGPD Article 5(1)(f) — security of personal data

// Email in localStorage
localStorage.setItem('userEmail', user.email);
localStorage.setItem('user_email', response.data.email);

// Phone number in sessionStorage
sessionStorage.setItem('phone', formData.phone);
sessionStorage.setItem('user_telephone', profile.tel);

// Full name
localStorage.setItem('firstName', user.firstName);
localStorage.setItem('last_name', user.lastName);
localStorage.setItem('fullName', `${first} ${last}`);

// Address
localStorage.setItem('address', user.address);
localStorage.setItem('postal_code', formData.zip);

// SSN / National ID
localStorage.setItem('ssn', user.socialSecurity);

// Date of birth
localStorage.setItem('date_of_birth', user.dob);
sessionStorage.setItem('birthday', profile.birthday);

// Reading PII back is also a sign it was stored
const email = localStorage.getItem('userEmail');
const phone = sessionStorage.getItem('phone');
