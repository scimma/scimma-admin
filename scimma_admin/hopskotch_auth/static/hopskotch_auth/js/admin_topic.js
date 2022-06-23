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
    admin_topic_table = $('#admin-topic-table').DataTable({
        'columns': [
            null,
            null,
            {'searchable': false},
            null,
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

    function onDeleteTopicCallback() {
        var trElem = $(this).closest('tr');
        var topicname = $(trElem).find('td.topicname').text();
        $('#deleteType').text('topic');
        $('#deleteName').text(topicname);
        confirm_modal.toggle();
    }

    function onConfirmDeleteCallback() {
        var objectName = $('#deleteName').text();
        trElem = $('tr').find(`[data-name='${objectName}']`);
        deleteTopic(trElem, objectName);
    }

    function deleteTopic(trElem, objectName) {
        dc_link = $('#dt_url').data().link;
        $.ajax({
            url: dc_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: objectName,
                
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                var row = admin_topic_table.row(trElem);
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

    $('body').on('click', '.deleteTopic', onDeleteTopicCallback);
    $('#confirmDelete').on('click', onConfirmDeleteCallback);
});