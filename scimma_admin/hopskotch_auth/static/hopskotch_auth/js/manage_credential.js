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
          {'className': 'topic_name'},
          {'className': 'topic_desc'},
          {'className': 'topic_access', 'searchable': false},
          {'searchable': false, 'orderable': false}
      ]
  });

  added_table = $('#added_table').DataTable({
    'info': false,
    'columns': [
        {'className': 'topic_name'},
        {'className': 'topic_desc'},
        {'className': 'topic_access'},
        {'className': 'perm_boxes', 'searchable': false, 'orderable': false},
        {'className': 'remove_button', 'searchable': false, 'orderable': false},
    ]
  })

  table_1_format = '\
    <tr>\
    <td class="topic_name">{}</td>\
    <td class="topic_desc">{}</td>\
    <td class="topic_access">{}</td>\
    <td class="perm_boxes">Read <input type="checkbox" class="form-check-input readCheck" checked> Write <input type="checkbox" class="form-check-input writeCheck"></td>\
    <td scope="col" class="remove_button"><button type="button" class="btn btn-danger removeFrom objectModifier">Remove</button></td>\
    </tr>\
  '

  perm_box_format = 'Read <input type="checkbox" class="form-check-input readCheck" checked> Write <input type="checkbox" class="form-check-input writeCheck">'
  remove_button_format = '<button type="button" class="btn btn-danger removeFrom objectModifier">Remove</button>'

  table_2_format = '\
    <tr>\
    <td class="topic_name">{}</td>\
    <td class="topic_desc">{}</td>\
    <td class="topic_access">{}</td>\
    <td><button type="button" class="btn btn-primary addToCur">Add</button></td>\
    </tr>\
  '

  add_button_format = '<button type="button" class="btn btn-primary addToCur">Add</button>'

  function addToCurCallback() {
      var trElem = $(this).closest('tr');
      var topic_name = $(trElem).find('td.topic_name').text();
      var topic_desc = $(trElem).find('td.topic_desc').text();
      var topic_access = $(trElem).find('td.topic_access').text();
      var credname = $('#idNameField').val();
      var trElem = $(this).closest('tr');
      var topic_name = $(trElem).find('td.topic_name').text();
      acp_link = $('#acp_url').data().link;
      $.ajax({
        url: acp_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            'credname': credname,
            'topicname': topic_name,
            'permission': ['Read'],
        },
        success: function (data, textStatus, jqXHR){
            avail_table.row(trElem).remove().draw(false);
            added_table.row.add([topic_name, topic_desc, topic_access, perm_box_format, remove_button_format]).draw(false);
            //var row = avail_table.row(trElem);
            //row.remove().draw();
            //$('#added_permissions > tbody:last-child').append(table_1_format.format(topic_name, topic_desc, topic_access));
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
      dacp_link = $('#rcp_url').data().link;
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
                'permission': ['Read', 'Write'],


            },
            success: function (data, textStatus, jqXHR){
                //var rowNode = avail_table.row.add($(table_2_format.format(topic_name, topic_desc, topic_access))).draw(false);
                //trElem.remove();
                added_table.row(trElem).remove().draw(false);
                avail_table.row.add([topic_name, topic_desc, topic_access, add_button_format]).draw(false);
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });
    }

    function onReadCallback() {
        var credname = $('#idNameField').val();
        var trElem = $(this).closest('tr');
        var isChecked = $(this).is(':checked');
        var topic_name = $(trElem).find('td.topic_name').text();
        var readLink = isChecked ? $('#acp_url').data().link : $('#rcp_url').data().link;
        $.ajax({
            url: readLink,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                'credname': credname,
                'topicname': topic_name,
                'permission': ['Read'],
            },
            success: function (data, textStatus, jqXHR){
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });
    }

    function onWriteCallback() {
        var credname = $('#idNameField').val();
        var trElem = $(this).closest('tr');
        var isChecked = $(this).is(':checked');
        var topic_name = $(trElem).find('td.topic_name').text();
        var readLink = isChecked ? $('#acp_url').data().link : $('#rcp_url').data().link;
        $.ajax({
            url: readLink,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                'credname': credname,
                'topicname': topic_name,
                'permission': ['Write'],
            },
            success: function (data, textStatus, jqXHR){
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                console.log('Complete: ' + textStatus);
            }
        });

        
    }

  $('body').on('click', '.addToCur', addToCurCallback);

  $('body').on('click', '.removeFrom', removeFromCallback);

  $('body').on('click', '.readCheck', onReadCallback);

  $('body').on('click', '.writeCheck', onWriteCallback);
} );
