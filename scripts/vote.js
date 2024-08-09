function debounce(callback, timeout = 400) {
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
        const searchRowDiv = document.createElement("div");
        searchRowDiv.classList.add("search-result");
        searchRowDiv.classList.add("movie-row");

        const posterElement = document.createElement("img");
        posterElement.alt = val.title;
        posterElement.src = `https://image.tmdb.org/t/p/w92${val.poster_path}`;
        posterElement.classList.add("search-movie-poster");
        searchRowDiv.appendChild(posterElement);

        const titleDiv = document.createElement("div");
        titleDiv.classList.add("movie-title-box");

        const titleSpan = document.createElement("span");
        titleSpan.textContent = val.title;
        titleSpan.classList.add("movie-title");
        const yearSpan = document.createElement("span");
        yearSpan.textContent = val.release_date;
        yearSpan.classList.add("movie-year");

        titleDiv.appendChild(titleSpan);
        titleDiv.appendChild(yearSpan);

        //<div class="movie-title-line"><span class="movie-title">{{.Title}}</span><span class="movie-year">({{.Year}})</span></div>
        
        searchRowDiv.appendChild(titleDiv);
        if (!val.suggested) {
            searchRowDiv.onclick = () => {
                fetch(`/api/suggest/${val.id}`, {
                    method: "POST"
                }).then(_ => {
                    location.reload();
                });
            }
        } else {
            searchRowDiv.classList.add("suggested-result");
            searchRowDiv.appendChild(document.createTextNode("Already suggested"));
        }

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
    confirmationDiv.hidden = !on;
    suggestionDiv.style.display = on ? "none" : "grid";
}
function onReplaceConfirmation() {
    fetch("/api/clearSuggestion", {"method": "POST"}).then(_ => location.reload());
}

function onVote(voteType, suggestion_id) {
    voteEl = document.getElementById(`vote-${suggestion_id}`);
    dir = voteEl.getAttribute("myVote");
    if ((voteType == "down" && dir == -1) || (voteType == "up" && dir == 1)) {
        voteType = "zero";
    }
    fetch(`/api/vote/${suggestion_id}/${voteType}`, {method: "POST"}).then(_ => location.reload())
}

document.addEventListener("DOMContentLoaded", () => {
    const rsvp_form = document.getElementById("rsvp-form");
    if (rsvp_form) registerSubmitForm(rsvp_form);   

    const myVotes = document.getElementsByClassName("movie-votes");
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