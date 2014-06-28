angular.module('efq').controller('QueueController', ['$scope', function ($scope) {
  $scope.pilots = [];
  socket.get('/pilotinqueue', function(pilots) {
    console.log('Pilots loaded: ', pilots);
    $scope.pilots = pilots;
    $scope.$digest();
  });
  socket.on('message', function(message) {
    console.log('QueueContoller got message: ', message);
    if (message.verb === 'create') {
      $scope.pilots.push(message.data);
    }
    $scope.$digest();
  });
}]);
