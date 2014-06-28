angular.module('efq').controller('MessagesController', ['$scope', function ($scope) {
  $scope.messages = [];
  socket.get('/messages', function(messages) {
    console.log('Messages loaded: ', messages);
    $scope.messages = messages;
    $scope.$digest();
  });
  socket.on('message', function(message) {
    console.log('MessageContoller got message: ', message);
    if (message.verb === 'create') {
      $scope.messages.push(message.data);
    }
    $scope.$digest();
  });
}]);
