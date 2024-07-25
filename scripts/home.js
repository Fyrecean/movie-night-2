document.addEventListener('DOMContentLoaded', function () {
    const registration_form = document.getElementById('registration-form');
    if (registration_form) registerSubmitForm(registration_form);
    const sign_in_form = document.getElementById('sign-in-form');
    if (sign_in_form) registerSubmitForm(sign_in_form);
    const logout_form = document.getElementById("logout-form");
    if (logout_form) registerSubmitForm(logout_form);
    const rsvp_form = document.getElementById("rsvp-form");
    if (rsvp_form) registerSubmitForm(rsvp_form);

});
const registerSubmitForm = (form) => {
    form.addEventListener('submit', function (event) {
        event.preventDefault();
        
        const formData = new FormData(form);
        const url = form.getAttribute("action")
        fetch(url, {
            method: 'POST',
            body: formData
        })
        .then(_ => location.reload());
    });
}