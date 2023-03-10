import './theme.scss';
import '@carbon/web-components/es/components/ui-shell';
import '@carbon/web-components/es/components/structured-list';
import '@carbon/web-components/es/components/data-table';
import '@carbon/web-components/es/components/pagination';
import '@carbon/web-components/es/components/form';
import '@carbon/web-components/es/components/input';
import '@carbon/web-components/es/components/button';
import '@carbon/web-components/es/components/notification';
import '@carbon/web-components/es/components/tag';
import '@carbon/web-components/es/components/list';
import '@carbon/web-components/es/components/select';
import '@carbon/web-components/es/components/modal';

function fixForm() {
  const buttons = document.querySelectorAll('bx-btn');
  buttons.forEach((button) => {
    let form: any = null;
    if (button.getAttribute('form_id')) {
      form = document.querySelector('form#' + button.getAttribute('form_id'));
    }

    // If it has "open_modal" attribute, open the modal
    const modalId = button.getAttribute('open_modal');

    button.addEventListener('click', () => {
      if (form) {
        form.submit();
      }
      if (modalId) {
        const modal: any = document.querySelector('bx-modal#' + modalId);
        if (modal) {
          modal.open = true;
        }
      }
    });
  });

  // Also do the same for bx-input and enter key
  const inputs = document.querySelectorAll('bx-input');
  inputs.forEach((input) => {
    input.addEventListener('keydown', (evt: any) => {
      if (!input.getAttribute('form_id')) {
        return;
      }

      if (evt.key === 'Enter') {
        const form: any = document.querySelector(
          'form#' + input.getAttribute('form_id')
        );
        if (form) {
          form.submit();
        }
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('bx-pagination').forEach((el) => {
    el.addEventListener('bx-pagination-changed-current', function (evt: any) {
      const pageSize = parseInt(el.getAttribute('page-size') || '0');
      const newPage = Math.ceil(evt.detail.start / pageSize) + 1;

      const searchParams = new URLSearchParams(window.location.search);
      searchParams.set('page', newPage.toString());
      window.location.search = searchParams.toString();
    });
  });

  // Add "active" if location has prefix, e.g. /admin/ -> /admin
  // For / only we need to check if the location is exactly /
  const pathname = window.location.pathname;
  let currentActive: any = null;
  document.querySelectorAll('bx-side-nav-link').forEach((el) => {
    const href = el.getAttribute('href');
    if (href === '/') {
      if (pathname === '/') {
        el.setAttribute('active', '');
      }
    } else if (pathname.startsWith(href || '')) {
      el.setAttribute('active', '');
      if (currentActive) {
        currentActive.removeAttribute('active');
      }
      currentActive = el;
    }
  });

  // Change "search" query parameter when the search field encounters Enter
  const searchToolbar: any = document.querySelector('bx-table-toolbar-search');
  if (searchToolbar) {
    const searchBar: any =
      searchToolbar.shadowRoot.querySelector('.bx--search-input');
    if (searchBar) {
      searchBar.addEventListener('keydown', (evt: any) => {
        if (evt.key === 'Enter') {
          const searchParams = new URLSearchParams(window.location.search);
          searchParams.set('search', searchBar.value);
          searchParams.set('page', '1');
          window.location.search = searchParams.toString();
        }
      });
    }
  }

  // For all bx-select, elements, using the "set_value" attribute, set the value
  // of the select element to the value of the attribute.
  document.querySelectorAll('bx-select').forEach((el: any) => {
    const setValue = el.getAttribute('set_value');
    if (setValue) {
      el.value = setValue;
    }
  });

  fixForm();
});
