function debounce(callback, timeout = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => callback.apply(this, args), timeout);
    };
}

const doSearch = debounce(async (query, resultsElement) => {
    const j = await fetch(`/api/search/${query}`).then(resp => resp.json());
    
    while (resultsElement.children.length > 0) {
        resultsElement.removeChild(resultsElement.children.item(0));
    }

    j.forEach(val => {
        const textElement = document.createTextNode(val.title);
        const searchRowDiv = document.createElement("div")
        searchRowDiv.appendChild(textElement);
        searchRowDiv.classList.add("search-result")
        resultsElement.appendChild(searchRowDiv);
    });
});

function onSearch(elementId, resultsId) {
    const inputElement = document.getElementById(elementId);
    const resultsElement = document.getElementById(resultsId);
    const searchQuery = inputElement.value;

    
    if (searchQuery == "") {
        while (resultsElement.children.length > 0) {
            resultsElement.removeChild(resultsElement.children.item(0));
        }
        return;
    }
    doSearch(searchQuery, resultsElement);
}


function setReplacementMessage(on) {
    const suggestionDiv = document.getElementById("my-suggestion");
    const confirmationDiv = document.getElementById("replace-confirmation");
    suggestionDiv.hidden = on;
    confirmationDiv.hidden = !on;
}
function onReplaceConfirmation() {
    fetch("/api/clearSuggestion", {"method": "POST"});
}

function onVote(voteType, suggestion_id) {
    fetch(`/api/vote/${suggestion_id}/${voteType}`, {method: "POST"}).then(_ => location.reload())
}

document.addEventListener("DOMContentLoaded", () => {
    const rsvp_form = document.getElementById("rsvp-form");
    if (rsvp_form) registerSubmitForm(rsvp_form);   

    const myVotes = document.getElementsByClassName("movie-votes")
    for(let i = 0; i < myVotes.length; i++) {
        const el = myVotes.item(i);
        const myVote = el.getAttribute("myVote");
        if (myVote === "-1") {
            el.querySelector(".down").classList.add("active-down");
        } else if (myVote === "1") {
            el.querySelector(".up").classList.add("active-up");

        }
    }
})