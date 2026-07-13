package cigar

import "context"

// PageIterator follows bounded server cursors and fails on cycles.
type PageIterator struct {
	client      *Client
	ctx         context.Context
	operationID string
	request     Request
	options     []CallOption
	seen        map[string]struct{}
	response    Response
	err         error
	done        bool
}

// Paginate constructs an iterator without performing I/O.
func (client *Client) Paginate(
	ctx context.Context,
	operationID string,
	request Request,
	options ...CallOption,
) (*PageIterator, error) {
	definition, ok := operations[operationID]
	if !ok || definition.Stream {
		return nil, &ValidationError{Message: "operation is unknown or streaming"}
	}
	return &PageIterator{
		client:      client,
		ctx:         ctx,
		operationID: operationID,
		request:     request,
		options:     append([]CallOption(nil), options...),
		seen:        make(map[string]struct{}),
	}, nil
}

// Next advances to the next page.
func (iterator *PageIterator) Next() bool {
	if iterator.done || iterator.err != nil {
		return false
	}
	response, err := iterator.client.call(
		iterator.ctx,
		iterator.operationID,
		iterator.request,
		iterator.options...,
	)
	if err != nil {
		iterator.err = err
		return false
	}
	iterator.response = response
	cursor := response.NextPageCursor()
	if cursor == "" {
		iterator.done = true
		return true
	}
	if _, duplicate := iterator.seen[cursor]; duplicate {
		iterator.err = &TransportError{Message: "pagination cursor cycle detected"}
		return false
	}
	iterator.seen[cursor] = struct{}{}
	iterator.request.pageCursor = cursor
	return true
}

// Response returns the current immutable page.
func (iterator *PageIterator) Response() Response { return iterator.response }

// Err returns the terminal pagination failure.
func (iterator *PageIterator) Err() error { return iterator.err }
