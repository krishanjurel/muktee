import java.util.Iterator;

public class BruteCollinearPoints {
    private Point[] points;
    private LineSegment[] lineSegments;
    private int numberOfSegments;
    private LineSegment[] tempLineSegments;
    private PointSlope[] pointSlopes;

    /**
     * create a private class to store a map of point and slope
     */
    private class PointSlope {
        public double slope;
        public Point point;

        public PointSlope(Point point, Double slope) {
            this.point = point;
            this.slope = slope;
        }
    }


    private void Sort(PointSlope[] pointSlopes) {
        int i = 0;
        int j = 0;
        for (i = 0; i < pointSlopes.length - 1; i++)
            for (j = i + 1; i < pointSlopes.length; j++) {
                if (pointSlopes[j].slope <= pointSlopes[i].slope) {
                    PointSlope temp = pointSlopes[i];
                    pointSlopes[i] = pointSlopes[j];
                    pointSlopes[j] = temp;
                    break;
                }
            }
    }


    BruteCollinearPoints(Point[] points) {
        int k = 0;
        this.points = points;
        numberOfSegments = 0;
        pointSlopes = new PointSlope[points.length - 1];
        lineSegments = new LineSegment[points.length];
        for (int i = 0; i < points.length; i++) {
            k = 0;
            for (int j = 0; j < points.length; j++) {
                if (points[i].IsEqual(points[j]) == false) {
                    pointSlopes[k] = new PointSlope(points[i], points[i].slopeTo(points[j]));
                    k++;
                }
            }
            //System.out.println("number of segments " + numberOfSegments);
            // sort the elements in the oder
            Sort(pointSlopes);
        }
    }


    private class LineSegmentIterator implements Iterator<LineSegment> {
        private LineSegment[] segments = lineSegments;
        private int totalCount = numberOfSegments;
        private int i = 0;

        public boolean hasNext() {
            return i < totalCount;
        }

        public LineSegment next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            return this.segments[i++];
        }
    }


    public Iterator<LineSegment> iterator() {
        return new LineSegmentIterator();
    }

    public Iterable<LineSegment> segments() {
        return new Iterable<LineSegment>() {
            public Iterator<LineSegment> iterator() {
                return new LineSegmentIterator();
            }
        };
    }
}
