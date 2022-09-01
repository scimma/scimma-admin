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

    added_template = '<tr scope="row">\
                      <td class="mem_id">{}</td>\
                      <td class="mem_name">{}</td>\
                      <td class="mem_email">{}</td>\
                      <td class="mem_perm"><select class="perm_select"><option selected>Member</option><option>Owner</option></select></td>\
                      <td class="remove_button"><button type="submit" class="btn btn-danger removeFrom">Remove</button></td>\
                      </tr>'
    avail_template = '<tr>\
                      <td class="add_id">{}</td>\
                      <td class="add_name">{}</td>\
                      <td class="add_email">{}</td>\
                      <td><button type="button" class="btn btn-primary addToCur">Add</button></td>\
                      </tr>'
    
    avail_table = $('#avail_members').DataTable({
        'info': false,
        'columns': [
            {'className': 'add_id'},
            {'className': 'add_name'},
            {'className': 'add_email'},
            {'searchable': false, 'orderable': false}
        ]
    });

    added_table = $('#added_members').DataTable({
        'info': false,
        'columns': [
            {'className': 'mem_id'},
            {'className': 'mem_name'},
            {'className': 'mem_email'},
            {'searchable': false, 'className': 'mem_perm'},
            {'searchable': false, 'orderable': false}
        ]
    });
    function onAddMemberCallback() {
        var trElem = $(this).closest('tr');
        var username = trElem.find('td.add_id').text();
        var groupname = $('#name_field').val();
        addMember(groupname, username, trElem);
    }

    function onRemoveMemberCallback() {
        var trElem = $(this).closest('tr');
        var username = trElem.find('td.mem_id').text();
        var groupname = $('#name_field').val();
        removeMember(groupname, username, trElem);
    }

    function onChangeMembershipCallback() {
        var trElem = $(this).closest('tr');
        var username = trElem.find('td.mem_id').text();
        var groupname = $('#name_field').val();
        changeMembership(groupname, username, trElem);
    }

    function addMember(groupname, username, trElem) {
        var mem_id = $(trElem).find('td.add_id').text();
        var mem_name = $(trElem).find('td.add_name').text();
        var mem_email = $(trElem).find('td.add_email').text();
        gam_link = $('#gam_url').data().link;
        $.ajax({
            url: gam_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: groupname,
                username: username
            },
            success: function (data, textStatus, jqXHR){
                avail_table.row(trElem).remove().draw(false);
                added_table.row.add([mem_id, mem_name, mem_email, '<select class="perm_select"><option selected>Member</option><option>Owner</option></select>', '<button type="submit" class="btn btn-danger removeFrom">Remove</button>']).draw(false);
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
            }
        });
    }

    function removeMember(groupname, username, trElem) {
        grm_link = $('#grm_url').data().link;
        var mem_id = $(trElem).find('td.mem_id').text();
        var mem_name = $(trElem).find('td.mem_name').text();
        var mem_email = $(trElem).find('td.mem_email').text();
        $.ajax({
            url: grm_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: groupname,
                username: username
            },
            success: function (data, textStatus, jqXHR){
                added_table.row(trElem).remove().draw(false);
                avail_table.row.add([mem_id, mem_name, mem_email, '<button type="button" class="btn btn-primary addToCur">Add</button>']).draw(false);
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
            }
        });
    }

    function changeMembership(groupname, username, trElem) {
        ucs_link = $('#ucs_url').data().link;
        perm_name = $(trElem).find('td.mem_perm > select').val();
        $.ajax({
            url: ucs_link,
            method: "POST",
            dataType: "json",
            headers: {
                "X-CSRFToken": getCookie('csrftoken')
            },
            data: {
                groupname: groupname,
                username: username,
                status: perm_name
            },
            success: function (data, textStatus, jqXHR){
                console.log('Successfully changed membership')
            },
            error: function(jqXHR, textStatus, errorThrown){
                console.log('Error: ' + errorThrown);
            },
            complete: function(jqXHR, textStatus) {
            }
        });
    }

    $('body').on('click', '.addToCur', onAddMemberCallback);
    $('body').on('click', '.removeFrom', onRemoveMemberCallback);
    $('body').on('change', '.mem_perm', onChangeMembershipCallback);
  });