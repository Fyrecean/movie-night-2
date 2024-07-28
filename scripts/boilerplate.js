const rejectNonNumeric = (form) => {
    form.addEventListener('input', function(event) {
        var target = event.target;
        if (target.tagName.toLowerCase() === 'input') {
            target.value = target.value.replace(/[^0-9]/g, '');
        }
    });
}

const registerSubmitForm = (form, redirect) => {
    form.addEventListener('submit', function (event) {
        event.preventDefault();
        
        const formData = new FormData(form);
        
        const url = form.getAttribute("action")
        fetch(url, {
            method: 'POST',
            body: formData
        }).then(response => {
            if (response.ok) {
                if (redirect) {
                    window.location.href = redirect
                } else {
                    location.reload()
                }
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