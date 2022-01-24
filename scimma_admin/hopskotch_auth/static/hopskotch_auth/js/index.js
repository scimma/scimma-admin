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
    confirm_modal = null;
    index_cred_table = $('#cred-table').DataTable({
        'info': false,
        'columns': [
            null,
            {'searchable': false},
            null,
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
    index_topic_table = $('#topic-table').DataTable({
        'info': false,
        'columns': [
            null,
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });
    index_group_table = $('#group-table').DataTable({
        'info': false,
        'columns': [
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
            {'searchable': false, 'orderable': false},
        ]
    });

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

    function onDeleteTopicCallback() {
        var trElem = $(this).closest('tr');
        var topicname = $(trElem).find('td.topicname').text();
        $('#deleteType').text('topic');
        $('#deleteName').text(topicname);
        confirm_modal.toggle();
    }

    function onDeleteGroupCallback() {
        var trElem = $(this).closest('tr');
        var groupname = $(trElem).find('td.groupname').text();
        $('#deleteType').text('group');
        $('#deleteName').text(groupname);
        confirm_modal.toggle();
    }

    function onConfirmDeleteCallback() {
        var objectType = $('#deleteType').text();
        var objectName = $('#deleteName').text();
        trElem = $('tr').find(`[data-name='${objectName}']`);
        switch (objectType) {
            case 'credential':
                deleteCredential(trElem, objectName);
                break;
            case 'topic':
                deleteTopic(trElem, objectName);
                break;
            case 'group':
                deleteGroup(trElem, objectName);
                break;
        }
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
                credname: objectName
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                var row = index_cred_table.row(trElem);
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

    function deleteTopic(trElem, objectName) {
        dt_link = $('#dt_url').data().link;
        $.ajax({
            url: dt_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: objectName
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                var row = index_topic_table.row(trElem);
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

    function deleteGroup(trElem, objectName) {
        dg_link = $('#dg_url').data().link;
        $.ajax({
            url: dg_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: objectName
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                var row = index_topic_table.row(trElem);
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
    $('body').on('click', '.deleteTopic', onDeleteTopicCallback);
    $('body').on('click', '.deleteGroup', onDeleteGroupCallback);
    $('#confirmDelete').on('click', onConfirmDeleteCallback);
});