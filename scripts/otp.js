document.addEventListener('DOMContentLoaded', function () {
    const otp_form = document.getElementById('otp-form');
    if (otp_form) registerSubmitForm(otp_form, "/");
    const otp_field = document.getElementById('otp');
    if (otp_field) rejectNonNumeric(otp_field);
});