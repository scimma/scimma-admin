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
          {'className': 'operations', 'searchable': false, 'orderable': false}
      ]
  });

  added_table = $('#added_table').DataTable({
    'info': false,
    'columns': [
        {'className': 'topic_name'},
        {'className': 'topic_desc'},
        {'className': 'topic_access'},
        {'className': 'operations', 'searchable': false, 'orderable': false},
    ]
  })
    progress_spinner = "<span class=\"spinner-border spinner-border-sm\" role=\"status\" aria-hidden=\"true\"></span>";
    
    function addPermCallback(){
        var credname = $('#idNameField').val();
        var spanElem = $(this).closest('span');
        var trElem = $(this).closest('tr');
        var topic_name = $(trElem).find('td.topic_name').text();
        var topic_desc = $(trElem).find('td.topic_desc').text();
        var topic_access = $(trElem).find('td.topic_access').text();
        var op_name = $(spanElem).contents().filter(function(){return this.nodeType == Node.TEXT_NODE; }).text().trim();
        var readLink = $('#acp_url').data().link;
        
        $(this).addClass("disabled");
        $(this).text("");
        $(this).prepend(progress_spinner);
        
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
                'permission': [op_name],
            },
            success: function (data, textStatus, jqXHR){
            },
            error: function(jqXHR, textStatus, errorThrown){
                $(this).removeClass("disabled");
                $(this).text("Add");
                //TODO: show error to user
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                //add to other table, creating row if necessary
                let cur_row=added_table.row((idx, data) => data[0] == topic_name)
                if(cur_row.length==0)
                    cur_row=added_table.row.add([topic_name, topic_desc, topic_access, ""]).draw(false);
                console.log(cur_row);
                var otherTr=cur_row.node();
                $(otherTr).find('td.operations').append("<span display=\"inline-block\">"+op_name+"&nbsp;<button role=\"button\" style=\"padding-top: 0; padding-bottom:0;\" class=\"btn btn-sm btn-danger remPerm objectModifier\">Remove</button></span> <br>");
                //remove from this table, removing the whole row if empty
                spanElem.remove();
                var items = $(trElem).find('td.operations span').length;
                if(items==0)
                    avail_table.row(trElem).remove().draw(false);
            }
        });
    }
    
    function remPermCallback(){
        var credname = $('#idNameField').val();
        var spanElem = $(this).closest('span');
        var trElem = $(this).closest('tr');
        var topic_name = $(trElem).find('td.topic_name').text();
        var topic_desc = $(trElem).find('td.topic_desc').text();
        var topic_access = $(trElem).find('td.topic_access').text();
        var op_name = $(spanElem).contents().filter(function(){return this.nodeType == Node.TEXT_NODE; }).text().trim();
        var readLink = $('#rcp_url').data().link;
        var items = $(trElem).find('td.operations span').length; //should be computed only when ready to move elements
        $(this).addClass("disabled");
        $(this).text("");
        $(this).prepend(progress_spinner);
        
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
                'permission': [op_name],
            },
            success: function (data, textStatus, jqXHR){
            },
            error: function(jqXHR, textStatus, errorThrown){
                $(this).removeClass("disabled");
                $(this).text("Remove");
                //TODO: show error to user
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
                //add to other table, creating row if necessary
                let cur_row=avail_table.row((idx, data) => data[0] == topic_name)
                if(cur_row.length==0)
                    cur_row=avail_table.row.add([topic_name, topic_desc, topic_access, ""]).draw(false);
                console.log(cur_row);
                var otherTr=cur_row.node();
                $(otherTr).find('td.operations').append("<span display=\"inline-block\">"+op_name+"&nbsp;<button role=\"button\" style=\"padding-top: 0; padding-bottom:0;\" class=\"btn btn-sm btn-primary addPerm objectModifier\">Add</button></span> <br>");
                //remove from this table, removing the whole row if empty
                spanElem.remove();
                var items = $(trElem).find('td.operations span').length;
                if(items==0)
                    added_table.row(trElem).remove().draw(false);
            }
        });
    }
  
    $('body').on('click', '.addPerm', addPermCallback);
    $('body').on('click', '.remPerm', remPermCallback);
} );
