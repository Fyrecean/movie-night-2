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