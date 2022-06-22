String.prototype.format = function () {
    var i = 0, args = arguments;
    return this.replace(/{}/g, function () {
      return typeof args[i] != 'undefined' ? args[i++] : '';
    });
  };

  function getCookie(c_name)
  {
      if (document.cookie.length > 0)
      {
          c_start = document.cookie.indexOf(c_name + "=");
          if (c_start != -1)
          {
              c_start = c_start + c_name.length + 1;
              c_end = document.cookie.indexOf(";", c_start);
              if (c_end == -1) c_end = document.cookie.length;
              return unescape(document.cookie.substring(c_start,c_end));
          }
      }
      return "";
   }

$(document).ready(function() {
    admin_cred_table = $('#admin-cred-table').DataTable({
        'columns': [
            null,
            null,
            {'searchable': false},
            null,
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
    confirm_modal = null;

    deleteConfirmFormat = 'Are you sure you want to delete the {}: {}'

    function initializeModal() {
        confirm_modal = new bootstrap.Modal($('#confirmModal'), {
            keyboard: false
        })
    }

    function onDeleteCredCallback() {
        var trElem = $(this).closest('tr');
        var credname = $(trElem).find('td.credname').text();
        $('#deleteType').text('credential');
        $('#deleteName').text(credname);
        confirm_modal.toggle();
    }

    function onConfirmDeleteCallback() {
        var objectName = $('#deleteName').text();
        console.log(`[data-name='${objectName}']`);
        trElem = $('tr').find(`[data-name='${objectName}']`);
        deleteCredential(trElem, objectName);
    }

    function deleteCredential(trElem, objectName) {
        dc_link = $('#dc_url').data().link;
        $.ajax({
            url: dc_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                credname: objectName,
                
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                var row = admin_cred_table.row(trElem);
                console.log(row)
                row.remove().draw();
                confirm_modal.toggle();
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            },
            traditional: true,
        });
    }

    initializeModal();

    $('body').on('click', '.deleteCredential', onDeleteCredCallback);
    $('#confirmDelete').on('click', onConfirmDeleteCallback);
});