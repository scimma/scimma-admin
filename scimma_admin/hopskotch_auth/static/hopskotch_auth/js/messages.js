function show_alert(message, level) {
    var alertbox = $('#callback_alert');
    if (alertbox == null) return;
    $(alertbox).html('\
    <div class="alert alert-dismissable alert-' + level + ' "\
    role="alert">' + message + '\
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>\
    ');
}