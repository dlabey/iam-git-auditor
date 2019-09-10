package main

import (
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
)

type Worktree interface {
	Add(string) (plumbing.Hash, error)
	Commit(string, *git.CommitOptions) (plumbing.Hash, error)
	Remove(string) (plumbing.Hash, error)
	Status() (git.Status, error)
}

type Repository interface {
	CommitObject(plumbing.Hash) (*object.Commit, error)
	Push(*git.PushOptions) error
}
