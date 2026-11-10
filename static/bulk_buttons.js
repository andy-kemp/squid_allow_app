// Enables the bulk action buttons only while at least one domain is ticked.
function updateBulkButtons() {
    const enabled = document.querySelectorAll('input[name="selected_domains"]:checked').length > 0;
    document.querySelectorAll('[data-bulk]').forEach(function (btn) { btn.disabled = !enabled; });
}

function toggleAll(source) {
    document.querySelectorAll('input[name="selected_domains"]').forEach(function (box) {
        box.checked = source.checked;
    });
    updateBulkButtons();
}

document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('input[name="selected_domains"]').forEach(function (box) {
        box.addEventListener('change', updateBulkButtons);
    });
    const selectAll = document.getElementById('selectAll');
    if (selectAll) {
        selectAll.addEventListener('change', function () { toggleAll(this); });
    }
    updateBulkButtons();
});
