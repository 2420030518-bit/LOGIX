document.addEventListener("DOMContentLoaded", function(){
  const form = document.getElementById("uploadForm");
  const fileInput = document.getElementById("fileInput");
  const submitBtn = document.getElementById("submitBtn");
  const status = document.getElementById("status");
  const statusText = document.getElementById("statusText");
  const fileName = document.getElementById("fileName");

  if (fileInput) {
    fileInput.addEventListener("change", function(){
      if (fileInput.files && fileInput.files.length) {
        fileName.textContent = fileInput.files[0].name;
      } else {
        fileName.textContent = "No file chosen";
      }
    });
  }

  if (form) {
    form.addEventListener("submit", function(e){
      if(!fileInput || !fileInput.value) {
        e.preventDefault();
        alert("Please choose a log file (.log, .txt, .evtx).");
        return;
      }
      submitBtn.disabled = true;
      if (status) status.hidden = false;
      if (statusText) statusText.textContent = "Uploading and analyzing — please wait...";
      setTimeout(()=> {
        submitBtn.disabled = false;
        if (status) status.hidden = true;
      }, 35000);
    });
  }
});
