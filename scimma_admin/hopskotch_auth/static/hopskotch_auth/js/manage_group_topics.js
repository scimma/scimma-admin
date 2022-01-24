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
  table_1_format = '\
  <tr>\
  <td class="topic_name">{}</td>\
  <td class="topic_desc">{}</td>\
  <td class="topic_accs">{}</td>\
  <td class="topic_edit"><a class="btn btn-primary editButton" href="{}">Edit</button></td>\
  <td class="topic_remv"><button type="button" class="btn btn-danger removeButton">Remove</button>\
  </tr>\
  '
    avail_table = null;
    edit_modal = null;

    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']

    function initializeTable() {
      avail_table = $('#avail_table').DataTable({
        'info': false,
        'columns': [
            null,
            null,
            {'searchable': false},
            {'searchable': false, 'orderable': false}
        ],
      });
    }

    function initializeModal() {
      modalElem = $('#topicPermEditModal');
      edit_modal = new bootstrap.Modal($('#topicPermEditModal'), {
        keyboard: false
      })
    }

    function removeFromCallback() {
      var trElem = $(this).closest("tr");
      var topicname = $(trElem).find('td.topic_name').text();
      var topicdesc = $(trElem).find('td.topic_desc').text();
      var topicaccess = $(trElem).find('td.topic_accs').text();
      rtg_link = $('#rtg_url').data().link;
      $.ajax({
        url: rtg_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            groupname: $('#name_field').val(),
            topicname: topicname
        },
        success: function (data, textStatus, jqXHR){
            trElem.remove();
        },
        error: function(jqXHR, textStatus, errorThrown){
            console.log('Error: ' + errorThrown);
        },
        complete: function(jqXHR, textStatus) {
        }
      });
    }

    function createTopicCallback() {
      var topicname = $('#input_create_topic').val();
      var groupname = $('#name_field').val();
      ctg_link = $('#ctg_url').data().link;

      $.ajax({
        url: ctg_link,
        method: "POST",
        dataType: "json",
        headers: {
            "X-CSRFToken": getCookie('csrftoken')
        },
        data: {
            groupname: groupname,
            topicname: topicname
        },
        success: function (data, textStatus, jqXHR){
          var editpath = data.editpath;
          var topic_name = groupname + '.' + topicname;
          var topic_desc = '';
          var topic_access = groupname;
          $('#added_table > tbody:last-child').append(table_1_format.format(topic_name, topic_desc, topic_access, editpath));
        },
        error: function(jqXHR, textStatus, errorThrown){
            console.log('Error: ' + errorThrown);
        },
        complete: function(jqXHR, textStatus) {
        }
    });
    }

    initializeTable();

    initializeModal();

    $('body').on('click', '.removeButton', removeFromCallback);

    $('#confirm_create_topic').on('click', createTopicCallback)
  }
);
