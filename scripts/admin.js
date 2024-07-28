function loadMovie() {
    const formEl = document.getElementById("admin-suggestion");
    const apiKey = formEl.getAttribute('apiKey');
    const form = new FormData(formEl);
    const id = form.get("movie-id");

    fetch("https://api.themoviedb.org/3/movie/" + id + "?api_key="+apiKey)
        .then(response => response.json())
        .then(json => {
            const movieDetailsDiv = document.getElementById('movie-details');
            while (movieDetailsDiv.firstChild) {
                movieDetailsDiv.removeChild(movieDetailsDiv.firstChild);
            }

            const titlePara = document.createElement('p');
            titlePara.textContent = "Title: " + json.title;
            movieDetailsDiv.appendChild(titlePara);

            const releaseDatePara = document.createElement('p');
            releaseDatePara.textContent = "Release Date: " + json.release_date;
            movieDetailsDiv.appendChild(releaseDatePara);

            const runtimePara = document.createElement('p');
            runtimePara.textContent = "Runtime: " + json.runtime + " minutes";
            movieDetailsDiv.appendChild(runtimePara);

            const posterImg = document.createElement('img');
            // posterImg.setAttribute('width', '100px');
            posterImg.src = "https://image.tmdb.org/t/p/w92" + json.poster_path;
            movieDetailsDiv.appendChild(posterImg);
        });
}

document.getElementById('schedule-form').addEventListener('submit', function(event) {
    event.preventDefault();

    const year = 2024;//document.getElementById('year').value;
    const month = document.getElementById('month').value.padStart(2, '0');
    const day = document.getElementById('day').value.padStart(2, '0');
    const hour = document.getElementById('hour').value.padStart(2, '0');
    const minute = document.getElementById('minute').value.padStart(2, '0');

    const rfc3339String = `${year}-${month}-${day}T${hour}:${minute}:00Z`;
    const url = `/api/admin/schedule-event/${rfc3339String}`;

    fetch(url, {
        method: "POST"
    })
        .then(response => {
            if (response.ok) {
                console.log('Event scheduled successfully:', response);
            } else {
                console.error("Error: ", response)
            }
        })
});