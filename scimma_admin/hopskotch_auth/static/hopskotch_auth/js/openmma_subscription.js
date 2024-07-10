function getCookie(c_name){
	if (document.cookie.length > 0){
		c_start = document.cookie.indexOf(c_name + "=");
		if (c_start != -1){
			c_start = c_start + c_name.length + 1;
			c_end = document.cookie.indexOf(";", c_start);
			if (c_end == -1) c_end = document.cookie.length;
			return unescape(document.cookie.substring(c_start,c_end));
		}
	}
	return "";
}

$(document).ready(function() {
	subscription_error_modal = null;

	function initializeSubscriptionErrorModal() {
		subscription_error_modal = new bootstrap.Modal($('#subscribeErrorModal'), {
			keyboard: true
		});
	}

	function onSubscribeOpenMMA() {
		subscribe_link = $('#openmma_subscribe_url').data().link;
		subscribe_button = $('#subscribeBtn');
		subscribe_button.addClass("disabled");
		subscribe_button.text("\u{A0}Subscribing...");
		subscribe_button.prepend("<span class=\"spinner-border spinner-border-sm\" role=\"status\" aria-hidden=\"true\"></span>");
		$.ajax({
			url: subscribe_link,
			method: "POST",
			dataType: "json",
			headers: {
				"X-CSRFToken": getCookie('csrftoken')
			},
			data: {
			},
			success: function (data, textStatus, jqXHR){
				$('#openmma_subscribed')[0].style.display="block";
				$('#openmma_unsubscribed')[0].style.display="none";
			},
			error: function(jqXHR, textStatus, errorThrown){
				$("#subscribeErrorModal").find('#error-text').text(
					"Failed to subscribe to the OpenMMA mailing list.");
				subscription_error_modal.show()
				console.log('Error: ' + errorThrown);
			},
			complete: function(jqXHR, textStatus) {
				subscribe_button.removeClass("disabled");
				subscribe_button.text("Subscribe");
			},
			traditional: true,
		});
		
	}
	function onUnsubscribeOpenMMA() {
		unsubscribe_link = $('#openmma_unsubscribe_url').data().link;
		unsubscribe_button = $('#unsubscribeBtn');
		unsubscribe_button.addClass("disabled");
		unsubscribe_button.text("\u{A0}Unsubscribing...");
		unsubscribe_button.prepend("<span class=\"spinner-border spinner-border-sm\" role=\"status\" aria-hidden=\"true\"></span>");
		$.ajax({
			url: unsubscribe_link,
			method: "POST",
			dataType: "json",
			headers: {
				"X-CSRFToken": getCookie('csrftoken')
			},
			data: {
			},
			success: function (data, textStatus, jqXHR){
				$('#openmma_subscribed')[0].style.display="none";
				$('#openmma_unsubscribed')[0].style.display="block";
			},
			error: function(jqXHR, textStatus, errorThrown){
				$("#subscribeErrorModal").find('#error-text').text(
					"Failed to unsubscribe from the OpenMMA mailing list.");
				subscription_error_modal.show()
				console.log('Error: ' + errorThrown);
			},
			complete: function(jqXHR, textStatus) {
				unsubscribe_button.removeClass("disabled");
				unsubscribe_button.text("Unsubscribe");
			},
			traditional: true,
		});
		
	}

	initializeSubscriptionErrorModal()
	$('body').on('click', '.subscribeOpenMMA', onSubscribeOpenMMA);
	$('body').on('click', '.unsubscribeOpenMMA', onUnsubscribeOpenMMA);
});