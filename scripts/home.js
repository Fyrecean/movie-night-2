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

const rejectNonNumeric = (form) => {
    form.addEventListener('input', function(event) {
        var target = event.target;
        if (target.tagName.toLowerCase() === 'input') {
            target.value = target.value.replace(/[^0-9]/g, '');
        }
    });
}

const registerSubmitForm = (form) => {
    form.addEventListener('submit', function (event) {
        event.preventDefault();
        
        const formData = new FormData(form);
        
        const url = form.getAttribute("action")
        fetch(url, {
            method: 'POST',
            body: formData
        }).then(response => {
            if (response.ok) {
                location.reload()
            } else {
                response.json().then(json => {
                    const bad_field = form.elements[json.field]
                    if (!bad_field.classList.contains("form-error")) {
                        bad_field.classList.add("form-error");
                        bad_field.insertAdjacentHTML('afterend', '<p class="error">'+ json.error +'</p>');
                    }
                });
            }
        }).catch(error => console.error(error));
    });
}