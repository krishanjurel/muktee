1. background.jpg image is used as the backgroud image.
2. the original greenscreen-asteroid.mp4 is used as a color mask selector.
3. the slider, sets the lower bound of the mean of the color mask as tens percentage of slider value. 
    if mean is 200, and slider is 5, then lowerbound = (200*50)/100 = 100.
    it means all greeen color value more than 100 will be considered as greenscreen and will be replaced.

  