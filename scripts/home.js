document.addEventListener('DOMContentLoaded', function () {
    const registration_form = document.getElementById('registration-form');
    if (registration_form) registerSubmitForm(registration_form);

    const registration_phone_field = document.getElementById('register-phone');
    if (registration_phone_field) rejectNonNumeric(registration_phone_field);

    const sign_in_form = document.getElementById('sign-in-form');
    if (sign_in_form) registerSubmitForm(sign_in_form);

    const sign_in_phone_field = document.getElementById('sign-in-phone');
    if (sign_in_phone_field) rejectNonNumeric(sign_in_phone_field);

    const logout_form = document.getElementById("logout-form");
    if (logout_form) registerSubmitForm(logout_form);

    const rsvp_form = document.getElementById("rsvp-form");
    if (rsvp_form) registerSubmitForm(rsvp_form);   
});