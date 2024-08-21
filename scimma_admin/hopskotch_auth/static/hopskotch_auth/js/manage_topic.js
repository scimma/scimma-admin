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
            {'className': 'permissions', 'searchable': false, 'orderable': false},
        ]
    });

    added_table = $('#added_groups').DataTable({
        'info': false,
        'columns': [
            {'className': 'group_name'},
            {'className': 'permissions', 'searchable': false, 'orderable': false},
        ]
    })
    
    progress_spinner = "<span class=\"spinner-border spinner-border-sm\" role=\"status\" aria-hidden=\"true\"></span>";
    
    function addPermCallback(){
        var spanElem = $(this).closest('span');
        var brElem = $(spanElem).next();
        var trElem = $(this).closest('tr');
        var groupname = $(trElem).find('td.group_name').text();
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        var op_name = $(spanElem).contents().filter(function(){return this.nodeType == Node.TEXT_NODE; }).text().trim();
        var readLink = $('#agp_url').data().link;
        
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
                topicname: topicname,
                groupname: groupname,
                permissions: op_name,
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
                let cur_row=added_table.row((idx, data) => data[0] == groupname)
                if(cur_row.length==0)
                    cur_row=added_table.row.add([groupname, ""]).draw(false);
                var otherTr=cur_row.node();
                $(otherTr).find('td.permissions').append("<span display=\"inline-block\">"+op_name+"&nbsp;<button role=\"button\" style=\"padding-top: 0; padding-bottom:0;\" class=\"btn btn-sm btn-danger remPerm objectModifier\">Remove</button></span> <br>");
                //remove from this table, removing the whole row if empty
                spanElem.remove();
                brElem.remove();
                var items = $(trElem).find('td.permissions span').length;
                if(items==0)
                    avail_table.row(trElem).remove().draw(false);
            }
        });
    }
    
    function remPermCallback(){
        var spanElem = $(this).closest('span');
        var brElem = $(spanElem).next();
        var trElem = $(this).closest('tr');
        var groupname = $(trElem).find('td.group_name').text();
        var topicname = $('#id_owning_group_field').val() + '.' + $('#id_name_field').val();
        var op_name = $(spanElem).contents().filter(function(){return this.nodeType == Node.TEXT_NODE; }).text().trim();
        var readLink = $('#rgp_url').data().link;
        var items = $(trElem).find('td.permissions span').length; //should be computed only when ready to move elements
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
                topicname: topicname,
                groupname: groupname,
                permissions: op_name,
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
                let cur_row=avail_table.row((idx, data) => data[0] == groupname)
                if(cur_row.length==0)
                    cur_row=avail_table.row.add([groupname, ""]).draw(false);
                var otherTr=cur_row.node();
                $(otherTr).find('td.permissions').append("<span display=\"inline-block\">"+op_name+"&nbsp;<button role=\"button\" style=\"padding-top: 0; padding-bottom:0;\" class=\"btn btn-sm btn-primary addPerm objectModifier\">Add</button></span> <br>");
                //remove from this table, removing the whole row if empty
                spanElem.remove();
                brElem.remove();
                var items = $(trElem).find('td.permissions span').length;
                if(items==0)
                    added_table.row(trElem).remove().draw(false);
            }
        });
    }

    $('body').on('click', '.addPerm', addPermCallback);
    $('body').on('click', '.remPerm', remPermCallback);
});