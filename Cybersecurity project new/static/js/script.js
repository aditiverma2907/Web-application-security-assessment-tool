document.addEventListener('DOMContentLoaded', () => {
  const scanForm = document.getElementById('scanForm');

  if (scanForm) {
    scanForm.addEventListener('submit', () => {
      const button = scanForm.querySelector('button[type="submit"]');
      const spinner = scanForm.querySelector('.btn-spinner');
      if (button) {
        button.classList.add('is-loading');
        button.setAttribute('disabled', 'disabled');
      }
      if (spinner) {
        spinner.classList.remove('d-none');
      }
    });
  }
});
