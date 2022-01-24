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
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite'];
  line_count = $('#added_permissions > tbody > tr').length;

  function initializeModal() {
    modalElem = $('#topicPermEditModal');
    edit_modal = new bootstrap.Modal($('#topicPermEditModal'), {
      keyboard: false
    })
  }

  avail_table = $('#avail_table').DataTable({
      'info': false,
      'columns': [
          null,
          null,
          {'searchable': false},
          {'searchable': false, 'orderable': false}
      ]
  });

  table_1_format = '\
    <tr>\
    <td class="topic_name">{}</td>\
    <td class="topic_desc">{}</td>\
    <td class="topic_access">{}</td>\
    <td class="edit_button"><button type="button" class="btn btn-primary editButton">Edit</button>\
    <td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom objectModifier">Remove</button></td>\
    </tr>\
  '

  table_2_format = '\
    <tr>\
    <td class="topic_name">{}</td>\
    <td class="topic_desc">{}</td>\
    <td class="topic_access">{}</td>\
    <td><button type="button" class="btn btn-primary addToCur">Add</button></td>\
    </tr>\
  '

  function addToCurCallback() {
      var trElem = $(this).closest('tr');
      var topic_name = $(trElem).find('td.topic_name').text();
      var topic_desc = $(trElem).find('td.topic_desc').text();
      var topic_access = $(trElem).find('td.topic_access').text();
      var credname = $('#idNameField').val();
      var trElem = $(this).closest('tr');
      var topic_name = $(trElem).find('td.topic_name').text();
      aacp_link = $('#aacp_url').data().link;
      $.ajax({
        url: aacp_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            'credname': credname,
            'topicname': topic_name,
        },
        success: function (data, textStatus, jqXHR){
            console.log(table_1_format.format(topic_name, topic_desc, topic_access));
            var row = avail_table.row(trElem);
            row.remove().draw();
            $('#added_permissions > tbody:last-child').append(table_1_format.format(topic_name, topic_desc, topic_access));
        },
        error: function(jqXHR, textStatus, errorThrown){
            console.log('Error: ' + errorThrown);
        },
        complete: function(jqXHR, textStatus) {
            console.log('Complete: ' + textStatus);
        }
    });
      
  }

  function removeFromCallback() {
      var trElem = $(this).closest('tr');
      var credname = $('#idNameField').val();
      var topic_name = $(trElem).find('td.topic_name').text();
      var topic_desc = $(trElem).find('td.topic_desc').text();
      var topic_access = $(trElem).find('td.topic_access').text();
      dacp_link = $('#dacp_url').data().link;
      $.ajax({
            url: dacp_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                'credname': credname,
                'topicname': topic_name,
            },
            success: function (data, textStatus, jqXHR){
                var rowNode = avail_table.row.add($(table_2_format.format(topic_name, topic_desc, topic_access))).draw(false);
                trElem.remove();
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });
    }


  // Things to do
  //  - Get permissions you are able to turn on/off
  //  - Check what permissions are currently attached to the credential
  //  - Set UI to reflect both what permissions are (un)available and (un)set
  //   * Permissions that aren't available need to be grayed out
  //  - After submitting then do a check for what permissions are already there and change accordingly
  function editPermCallback() {
      var credname = $('#idNameField').val();
      var trElem = $(this).closest('tr');
      var topic_name = $(trElem).find('td.topic_name').text();
      gact_link = $('#gact_url').data().link;
      $.ajax({
        url: gact_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            'credname': credname,
            'topicname': topic_name,
        },
        success: function (data, textStatus, jqXHR){
            console.log('Success: ' + textStatus);
            console.log(credname);
            console.log(data);
            console.log(topic_name);
            $('#currently_editing').val(topic_name);
            for (let i = 0; i < all_perms.length; i++) {
                $('#' + all_perms[i] + '_perm').prop('checked', false);
                $('#' + all_perms[i] + '_perm').prop('disabled', true);
            }
            for (let i = 0; i < data.data.length; i++) {
                $('#' + data.data[i].operation + '_perm').prop('disabled', false);
            }
            for (let i = 0; i < data.cred_data.length; i++) {
                $('#' + data.cred_data[i] + '_perm').prop('checked', true);
            }
            edit_modal.toggle();
        },
        error: function(jqXHR, textStatus, errorThrown){
            console.log('Error: ' + errorThrown);
        },
        complete: function(jqXHR, textStatus) {
            console.log('Complete: ' + textStatus);
        }
    });
  }

  function saveEditCallback() {
      var selected_perms = [];
      var boxes = $('input[name=permCheck]:checked');
      var credname = $('#idNameField').val();
      var topicname = $('#currently_editing').val();
      boxes.each(function() {
          selected_perms.push($(this).val());
      });
      bscp_link = $('#bscp_url').data().link;
      $.ajax({
        url: bscp_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            credname: credname,
            topicname: topicname,
            permissions: selected_perms
        },
        success: function (data, textStatus, jqXHR){
            console.log('Success: ' + textStatus);
            edit_modal.toggle();
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

  $('body').on('click', '.addToCur', addToCurCallback);

  $('body').on('click', '.removeFrom', removeFromCallback);

  $('body').on('click', '.editButton', editPermCallback);

  $('#save_edit').on('click', saveEditCallback);

  /*
  
  $('#avail_table').on('click', '.addToCur', function() {
      var trElem = $(this).closest("tr");
      var d = avail_table.row( trElem ).data();
      var row = avail_table.row(trElem);
      row.remove().draw();
      $('#added_permissions > tbody:last-child').append(create_line(line_count, d[0], d[1], d[2]));
      line_count = line_count + 1;

  })

  $('#added_permissions').on('click', '.removeFrom', function() {
      var trElem = $(this).closest('tr');
      var topic_name = trElem.children('td.topic_name').find('input').val();
      var topic_desc = trElem.children('td.topic_desc').find('input').val();
      var topic_access = trElem.children('td.topic_access').text();
      avail_table.row.add(
          [
              topic_name,
              topic_desc,
              topic_access,
              '<button type="button" class="btn btn-primary addToCur objectModifier">Add</button>'
          ]
      ).draw();
      trElem.remove();
      if ($($(this).closest('.readBox').is(':checked'))) {
        $.ajax({
            url: $('#rcp_url').data().link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                credname: $('#idNameField').val(),
                perm_name: topic_name,
                perm_perm: 'read'
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });
      }
      if ($($(this).closest('.writeBox').is(':checked'))) {
        $.ajax({
            url: $('#rcp_url').data().link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                credname: $('#idNameField').val(),
                perm_name: topic_name,
                perm_perm: 'write'
            },
            success: function (data, textStatus, jqXHR){
                console.log('Success: ' + textStatus);
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });
      }

  });

  $('body').on('click', '.permBox', function() {
      var classList = $(this).attr('class').split(/\s+/);
      var trElem = $(this).closest('tr');
      var topicName = trElem.children('td.topic_name').find('input').val();
      var acp_url = 'none';
      console.log('clicked permbox')
      if ($(this).is(':checked')) {
          url = $('#acp_url').data().link;
      }
      else {
          url  = $('#rcp_url').data().link;
      }
      var perm = 'none'
      console.log(classList);
      if(classList[1] == 'readBox'){
          perm = 'read';
      }
      else {
          perm = 'write';
      }
      $.ajax({
        url: url,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            credname: $('#idNameField').val(),
            perm_name: topicName,
            perm_perm: perm
        },
        success: function (data, textStatus, jqXHR){
            console.log('Success: ' + textStatus);
        },
        error: function(jqXHR, textStatus, errorThrown){
            console.log('Error: ' + errorThrown);
        },
        complete: function(jqXHR, textStatus) {
            console.log('Complete: ' + textStatus);
        }
    });
  });
  */
} );
