const copyrightYear = document.querySelector("#copyright-year");
const passwordField = document.getElementById("password");
const confirmPasswordField = document.getElementById("confirm-password");
const togglePassword = document.querySelector(".password-toggle-icon i");
const confirmTogglePassword = document.querySelector(
  ".confirm-password-toggle-icon i",
);
const toastContainer = document.querySelector(".toast-container");
const toastCloseButton = document.querySelector(".toast-btn");
copyrightYear.textContent = (function () {
  return new Date().getFullYear();
})();

toastCloseButton.addEventListener("click", () => {
  toastContainer.remove();
});

setTimeout(() => {
  toastContainer.remove();
}, 5000);

if (togglePassword) {
  togglePassword.addEventListener("click", function () {
    if (passwordField.type === "password") {
      passwordField.type = "text";
      togglePassword.classList.remove("fa-eye");
      togglePassword.classList.add("fa-eye-slash");
    } else {
      passwordField.type = "password";
      togglePassword.classList.remove("fa-eye-slash");
      togglePassword.classList.add("fa-eye");
    }
  });
}
if (confirmTogglePassword) {
  confirmTogglePassword.addEventListener("click", function () {
    if (confirmPasswordField.type === "password") {
      confirmPasswordField.type = "text";
      confirmTogglePassword.classList.remove("fa-eye");
      confirmTogglePassword.classList.add("fa-eye-slash");
    } else {
      confirmPasswordField.type = "password";
      confirmTogglePassword.classList.remove("fa-eye-slash");
      confirmTogglePassword.classList.add("fa-eye");
    }
  });
}

document.addEventListener("DOMContentLoaded", function () {
  //capture a user's timezone to a cookie
  let userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  document.cookie = "user_timezone=" + userTimezone + "; path=/";
});
