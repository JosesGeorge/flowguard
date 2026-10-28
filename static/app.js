document.querySelectorAll("[data-modal]").forEach((button) => {
  button.addEventListener("click", () => document.getElementById(button.dataset.modal).classList.add("open"));
});
document.querySelectorAll(".modal-close").forEach((button) => {
  button.addEventListener("click", () => button.closest(".modal").classList.remove("open"));
});
document.querySelectorAll(".modal").forEach((modal) => {
  modal.addEventListener("click", (event) => {
    if (event.target === modal) modal.classList.remove("open");
  });
});
