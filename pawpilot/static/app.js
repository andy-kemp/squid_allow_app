// Bulk buttons enable only while something is ticked; the filter box hides non-matching rows.
(function () {
  function boxes() { return Array.from(document.querySelectorAll('input[data-select]')); }
  function visible(box) { return !box.closest('tr').hidden; }
  function update() {
    var any = boxes().some(function (b) { return b.checked; });
    document.querySelectorAll('[data-bulk]').forEach(function (btn) { btn.disabled = !any; });
  }
  document.addEventListener('DOMContentLoaded', function () {
    boxes().forEach(function (b) { b.addEventListener('change', update); });
    var all = document.getElementById('selectAll');
    if (all) {
      all.addEventListener('change', function () {
        boxes().forEach(function (b) { b.checked = all.checked && visible(b); });
        update();
      });
    }
    var filter = document.querySelector('[data-filter]');
    if (filter) {
      filter.addEventListener('input', function () {
        var q = filter.value.trim().toLowerCase();
        document.querySelectorAll('tbody tr[data-row]').forEach(function (tr) {
          tr.hidden = q !== '' && tr.textContent.toLowerCase().indexOf(q) === -1;
          if (tr.hidden) { var b = tr.querySelector('input[data-select]'); if (b) { b.checked = false; } }
        });
        update();
      });
    }
    update();
  });
})();
