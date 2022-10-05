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
table_1_format = '<tr scope="row">\
<td scope="col" class="group_name">{}</td>\
<td scope="col" class="perm_fields"><button type="button" class="btn btn-primary editPerm">Edit</button></td>\
<td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom">Remove</button></td>\
</tr>'

added_perm_format = '<div>\
Read <input class="readCheck" type="checkbox" checked> Write <input class="writeCheck" type="checkbox" >\
</div>'

table_2_format = '<tr scope="row">\
<td scope="col" class="group_name">{}</td>\
<td scope="col" class="perm_fields">\
  <div>\
    Read <input class="readCheck" type="checkbox" checked> Write <input class="writeCheck" type="checkbox" >\
  </div>\
  </td>\
<td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom">Remove</button></td>\
</tr>'

$(document).ready(function() {
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite'];
    edit_modal = null;
    function initializeModal() {
        modalElem = $('#topicPermEditModal');
        edit_modal = new bootstrap.Modal($('#topicPermEditModal'), {
          keyboard: false
        })
      }

    $('#id-selectOwnerForm #submit-id-cancel').click( function(event) {
        event.preventDefault();
        owner_select = $('#owner_select');
        select_field = owner_select.find('#owner_select')
        select_button = owner_select.find('#submit-id-cancel');
        owner_name = owner_select.val();
        if(owner_name == '')
        {
            return;
        }
        $('#owning_group').modal('toggle');
        $('#id_owning_group_field').val(owner_name)
    });

    avail_table = $('#avail_table').DataTable({
        'info': false,
        'columns': [
            {'className': 'group_name'},
            {'className': 'remove_button', 'searchable': false, 'orderable': false}
        ]
    });

    added_table = $('#added_groups').DataTable({
        'info': false,
        'columns': [
            {'className': 'group_name'},
            {'className': 'perm_fields', 'searchable': false, 'orderable': false},
            {'className': 'remove_button', 'searchable': false, 'orderable': false},
        ]
    })

    function addedGroupCallback() {
        var trElem = $(this).closest('tr');
        var groupname = trElem.find('td.group_name').text();
        console.log(groupname);
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        bsgp_link = $('#agp_url').data().link;
        $.ajax({
            url: bsgp_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: topicname,
                groupname: groupname,
                permissions: 'Read',
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                avail_table.row(trElem).remove().draw(false);
                added_table.row.add([groupname, added_perm_format, '<button type="button" class="btn btn-danger removeFrom">Remove</button>']).draw(false);
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

    function removedGroupCallback() {
        var trElem = $(this).closest('tr');
        var groupname = trElem.find('td.group_name').text();
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        bsgp_link = $('#rgp_url').data().link;
        $.ajax({
            url: bsgp_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: topicname,
                groupname: groupname,
                permissions: ['Read', 'Write'],
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                added_table.row(trElem).remove().draw(false);
                avail_table.row.add(
                    [
                        groupname,
                        '<button type="button" class="btn btn-primary addToCur">Add</button>'
                    ]
                ).draw();
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

    function onReadCallback() {
        var trElem = $(this).closest('tr');
        var isChecked = $(this).is(':checked');
        var groupname = $(trElem).find('td.group_name').text();
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        var gp_link = isChecked ? $('#agp_url').data().link : $('#rgp_url').data().link;
        $.ajax({
            url: gp_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: topicname,
                groupname: groupname,
                permissions: 'Read',
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                if (isChecked) {
                    show_alert('Successfully gave {} Read Permission'.format(groupname), 'success');
                }
                else {
                    show_alert("Successfully revoked {}'s Read Permission".format(groupname), 'success');
                }
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
                if (isChecked) {
                    show_alert('Failed to give {} Read Permission'.format(groupname), 'danger');
                }
                else {
                    show_alert("Failed to revoke {}'s Read Permission".format(groupname), 'danger');
                }
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            },
            traditional: true,
        });
    }

    function onWriteCallback() {
        var trElem = $(this).closest('tr');
        var isChecked = $(this).is(':checked');
        var groupname = $(trElem).find('td.group_name').text();
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        var gp_link = isChecked ? $('#agp_url').data().link : $('#rgp_url').data().link;
        $.ajax({
            url: gp_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                topicname: topicname,
                groupname: groupname,
                permissions: 'Write',
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
                if (isChecked) {
                    show_alert('Successfully gave {} Write Permission'.format(groupname), 'success');
                }
                else {
                    show_alert("Successfully revoked {}'s Write Permission".format(groupname), 'success');
                }
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
                if (isChecked) {
                    show_alert('Failed to give {} Write Permission'.format(groupname), 'danger');
                }
                else {
                    show_alert("Failed to revoke {}'s Write Permission".format(groupname), 'danger');
                }
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            },
            traditional: true,
        });
    }

    initializeModal();

    $('body').on('click', '.addToCur', addedGroupCallback);

    $('body').on('click', '.removeFrom', removedGroupCallback);

    $('body').on('click', '.readCheck', onReadCallback);

    $('body').on('click', '.writeCheck', onWriteCallback);
});